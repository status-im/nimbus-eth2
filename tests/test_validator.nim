# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  math,unittest, sequtils,
  ../beacon_chain/spec/[datatypes, digest, validator]

func sumCommittees(v: openArray[seq[ShardAndCommittee]]): int =
  for x in v:
    for y in x:
      inc result, y.committee.len

suite "Validators":
  ## For now just test that we can compile and execute block processing with mock data.
  ## https://github.com/status-im/nim-beacon-chain/issues/1
  ## https://github.com/sigp/lighthouse/blob/ba548e49a52687a655c61b443b6835d79c6d4236/beacon_chain/validator_shuffling/src/shuffle.rs
  test "Smoke validator shuffling":
    let
      validators = repeat(
        ValidatorRecord(
          status: ACTIVE
        ), 1024)

    # XXX the shuffling looks really odd, probably buggy
    let s = get_new_shuffling(Eth2Digest(), validators, 0)
    check:
      s.len == CYCLE_LENGTH
      sumCommittees(s) == validators.len() # all validators accounted for
