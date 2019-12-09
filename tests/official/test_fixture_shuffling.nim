# beacon_chain
# Copyright (c) 2018-Present Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Standard library
  os, unittest, sequtils,
  # Beacon chain internals
  ../../beacon_chain/spec/[datatypes, validator, digest],
  # Test utilities
  ../testutil,
  ./fixtures_utils

type
  Shuffling* = object
    seed*: Eth2Digest
    count*: uint64
    mapping*: seq[uint64]

# TODO: json tests were removed
const ShufflingDir = JsonTestsDir/const_preset/"phase0"/"shuffling"/"core"/"shuffle"

suite "Official - Shuffling tests [Preset: " & preset():
  timedTest "Shuffling a sequence of N validators" & preset():
    for file in walkDirRec(ShufflingDir):
      let t = parseTest(file, Json, Shuffling)
      let implResult = get_shuffled_seq(t.seed, t.count)
      check: implResult == mapIt(t.mapping, it.ValidatorIndex)
