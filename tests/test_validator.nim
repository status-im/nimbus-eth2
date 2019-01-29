# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  math,unittest, sequtils,
  ../beacon_chain/spec/[helpers, datatypes, digest, validator]

func sumCommittees(v: openArray[seq[Uint24]], reqCommitteeLen: int): int =
  for x in v:
    ## This only holds when num_validators is divisible by
    ## EPOCH_LENGTH * get_committee_count_per_slot(len(validators))
    ## as, in general, not all committees can be equally sized.
    assert x.len == reqCommitteeLen
    inc result, x.len

suite "Validators":
  ## For now just test that we can compile and execute block processing with mock data.
  ## https://github.com/status-im/nim-beacon-chain/issues/1
  ## https://github.com/sigp/lighthouse/blob/ba548e49a52687a655c61b443b6835d79c6d4236/beacon_chain/validator_shuffling/src/shuffle.rs
  test "Smoke validator shuffling":
    let
      num_validators = 32*1024
      validators = repeat(
        Validator(
          exit_epoch: FAR_FUTURE_EPOCH
        ), num_validators)
      s = get_shuffling(Eth2Digest(), validators, 0)
      committees = get_epoch_committee_count(len(validators)).int
    check:
      s.len == committees
       # 32k validators: EPOCH_LENGTH slots * committee_count_per_slot =
       # get_epoch_committee_count committees.
      sumCommittees(s, num_validators div committees) == validators.len() # all validators accounted for
