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
proc genMockPrivKeys(privkeys: var array[MIN_GENESIS_ACTIVE_VALIDATOR_COUNT, ValidatorPrivKey]) =
  for i in 0 ..< privkeys.len:
    let pair = newKeyPair()
    privkeys[i] = pair.priv

proc genMockPubKeys(
       pubkeys: var array[MIN_GENESIS_ACTIVE_VALIDATOR_COUNT, ValidatorPubKey],
       privkeys: array[MIN_GENESIS_ACTIVE_VALIDATOR_COUNT, ValidatorPrivKey]
     ) =
  for i in 0 ..< privkeys.len:
    pubkeys[i] = pubkey(privkeys[i])

# Ref array necessary to limit stack usage / binary size
var MockPrivKeys*: ref array[MIN_GENESIS_ACTIVE_VALIDATOR_COUNT, ValidatorPrivKey]
new MockPrivKeys
genMockPrivKeys(MockPrivKeys[])

var MockPubKeys*: ref array[MIN_GENESIS_ACTIVE_VALIDATOR_COUNT, ValidatorPubKey]
new MockPubKeys
genMockPubKeys(MockPubKeys[], MockPrivKeys[])

type MockKey = ValidatorPrivKey or ValidatorPubKey

template `[]`*[N: static int](a: array[N, MockKey], idx: ValidatorIndex): MockKey =
  a[idx.int]

when isMainModule:
  from blscurve import toHex

  echo "========================================"
  echo "Mock keys"
  for i in 0 ..< MIN_GENESIS_ACTIVE_VALIDATOR_COUNT:
    echo "  validator ", i
    echo "    seckey: ", MockPrivKeys[i].toHex()
    echo "    pubkey: ", MockPubKeys[i]
