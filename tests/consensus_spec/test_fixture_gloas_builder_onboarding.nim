# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  # Beacon chain internals
  ../../beacon_chain/spec/[beaconstate, forks, signatures],
  # Test utilities
  ../testblockutil,
  unittest2

from ../../beacon_chain/spec/datatypes/constants import BUILDER_WITHDRAWAL_PREFIX

const
  depositAmount = 32_000_000_000.Gwei

  validatorCredentials = block:
    var res: Eth2Digest
    res.data[0] = 0x02'u8
    res

func builderCredentials(tag: byte): Eth2Digest =
  var res: Eth2Digest
  res.data[0] = BUILDER_WITHDRAWAL_PREFIX
  res.data[31] = tag
  res

func mockPubkey(index: uint64): ValidatorPubKey =
  MockPrivKeys[index].toPubKey().toPubKey()

# `signer` selects the private key used; passing an index other than `index`
# yields a well-formed but invalid signature for that pubkey.
func pendingDeposit(
    index: uint64, credentials: Eth2Digest, signer: uint64): PendingDeposit =
  let
    pubkey = mockPubkey(index)
    data = DepositData(
      pubkey: pubkey,
      withdrawal_credentials: credentials,
      amount: depositAmount)
  PendingDeposit(
    pubkey: pubkey,
    withdrawal_credentials: credentials,
    amount: depositAmount,
    signature: get_deposit_signature(
      defaultRuntimeConfig.GENESIS_FORK_VERSION, data,
      MockPrivKeys[signer]).toValidatorSig(),
    slot: Slot(0))

func validatorDeposit(index: uint64, valid: bool): PendingDeposit =
  pendingDeposit(
    index, validatorCredentials, if valid: index else: index + 1000)

func builderDeposit(index: uint64, valid: bool, tag = 0'u8): PendingDeposit =
  pendingDeposit(
    index, builderCredentials(tag), if valid: index else: index + 1000)

func onboard(deposits: seq[PendingDeposit]): ref gloas.BeaconState =
  let state = (ref gloas.BeaconState)(
    pending_deposits: HashSeq[PendingDeposit].init(deposits))
  onboard_builders_from_pending_deposits(defaultRuntimeConfig, state[])
  state

suite "Gloas builder onboarding from pending deposits":
  test "valid, then invalid validator deposit still blocks builder onboarding":
    let state = onboard(@[
      validatorDeposit(0, valid = true),
      validatorDeposit(0, valid = false),
      builderDeposit(0, valid = true)])
    check:
      state[].builders.len == 0
      state[].pending_deposits.len == 3

  test "invalid, then valid validator deposit blocks builder onboarding":
    let state = onboard(@[
      validatorDeposit(0, valid = false),
      validatorDeposit(0, valid = true),
      builderDeposit(0, valid = true)])
    check:
      state[].builders.len == 0
      state[].pending_deposits.len == 3

  test "multiple mixed-validity validator deposits surrounding builder deposits":
    let state = onboard(@[
      validatorDeposit(0, valid = false),
      validatorDeposit(1, valid = false),
      validatorDeposit(0, valid = true),
      builderDeposit(0, valid = true, tag = 1),
      validatorDeposit(0, valid = false),
      builderDeposit(1, valid = true, tag = 2),   # onboards builder 1
      validatorDeposit(1, valid = false),         # tops up builder 1
      builderDeposit(0, valid = true, tag = 3),
      builderDeposit(1, valid = true, tag = 4)])  # tops up builder 1
    check:
      state[].builders.len == 1
      state[].builders.item(0).pubkey == mockPubkey(1)
      state[].builders.item(0).balance == 3 * depositAmount
      # Pubkey 0's five deposits stay pending, as does pubkey 1's validator
      # deposit from before the builder existed.
      state[].pending_deposits.len == 6
