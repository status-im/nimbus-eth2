# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Helper functions
import ../datatypes, sequtils, nimcrypto

func getShuffling(seed: Blake2_256_Digest, validatorCount: int): seq[int] {.noInit.}=
  # Pseudorandomly shuffles the validator set based on some seed

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
