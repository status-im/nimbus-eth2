# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Mocking validator public and private keys
# ---------------------------------------------------------------

import
  bearssl, eth/keys,
  ../../beacon_chain/spec/[datatypes, crypto, presets]

proc newKeyPair(rng: var BrHmacDrbgContext): BlsResult[tuple[pub: ValidatorPubKey, priv: ValidatorPrivKey]] =
  ## Generates a new public-private keypair
  ## This requires entropy on the system
  # The input-keying-material requires 32 bytes at least for security
  # The generation is deterministic and the input-keying-material
  # must be protected against side-channel attacks

  var ikm: array[32, byte]
  brHmacDrbgGenerate(rng, ikm)
  return ikm.keygen()

# this is being indexed inside "mock_deposits.nim" by a value up to `validatorCount`
# which is `num_validators` which is `MIN_GENESIS_ACTIVE_VALIDATOR_COUNT`
proc genMockPrivKeys(privkeys: var openarray[ValidatorPrivKey]) =
  let rng = newRng()
  for i in 0 ..< privkeys.len:
    let pair = newKeyPair(rng[])[]
    privkeys[i] = pair.priv

func genMockPubKeys(pubkeys: var openarray[ValidatorPubKey],
                    privkeys: openarray[ValidatorPrivKey]) =
  for i in 0 ..< privkeys.len:
    pubkeys[i] = toPubKey(privkeys[i])

# Ref array necessary to limit stack usage / binary size
var MockPrivKeys* = newSeq[ValidatorPrivKey](defaultRuntimePreset.MIN_GENESIS_ACTIVE_VALIDATOR_COUNT)
genMockPrivKeys(MockPrivKeys)

var MockPubKeys* = newSeq[ValidatorPubKey](defaultRuntimePreset.MIN_GENESIS_ACTIVE_VALIDATOR_COUNT)
genMockPubKeys(MockPubKeys, MockPrivKeys)

type MockKey = ValidatorPrivKey or ValidatorPubKey

template `[]`*[N: static int](a: array[N, MockKey], idx: ValidatorIndex): MockKey =
  a[idx.int]

when isMainModule:
  echo "========================================"
  echo "Mock keys"
  for i in 0 ..< defaultRuntimePreset.MIN_GENESIS_ACTIVE_VALIDATOR_COUNT:
    echo "  validator ", i
    echo "    seckey: ", MockPrivKeys[i].toHex()
    echo "    pubkey: ", MockPubKeys[i]
