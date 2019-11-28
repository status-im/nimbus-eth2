# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Mocking validator public and private keys
# ---------------------------------------------------------------

import
  # Specs
  ../../beacon_chain/spec/[datatypes, crypto]

# this is being indexed inside "mock_deposits.nim" by a value up to `validatorCount`
# which is `num_validators` which is `MIN_GENESIS_ACTIVE_VALIDATOR_COUNT`
let MockPrivKeys* = block:
  var privkeys: array[MIN_GENESIS_ACTIVE_VALIDATOR_COUNT, ValidatorPrivKey]
  for pk in privkeys.mitems():
    pk = newPrivKey()
  privkeys

let MockPubKeys* = block:
  var pubkeys: array[MIN_GENESIS_ACTIVE_VALIDATOR_COUNT, ValidatorPubKey]
  for idx, privkey in MockPrivKeys:
    pubkeys[idx] = pubkey(privkey)
  pubkeys

type MockKey = ValidatorPrivKey or ValidatorPubKey

template `[]`*[N: static int](a: array[N, MockKey], idx: ValidatorIndex): MockKey =
  a[idx.int]
