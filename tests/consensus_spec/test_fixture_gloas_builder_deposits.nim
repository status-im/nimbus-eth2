# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  unittest2,
  ../../beacon_chain/spec/[beaconstate, state_transition_block],
  ../../beacon_chain/validator_bucket_sort,
  ../testblockutil

const
  depositAmount = 32_000_000_000.Gwei
  currentEpoch = Epoch(2)

  builderCredentials = block:
    var res: Eth2Digest
    res.data[0] = BUILDER_WITHDRAWAL_PREFIX
    res

func mockPubkey(index: uint64): ValidatorPubKey =
  MockPrivKeys[index].toPubKey().toPubKey()

func builder(index: uint64, withdrawable_epoch: Epoch, balance: Gwei): Builder =
  Builder(
    pubkey: mockPubkey(index),
    balance: balance,
    withdrawable_epoch: withdrawable_epoch)

func depositRequest(index: uint64): BuilderDepositRequest =
  let
    pubkey = mockPubkey(index)
    signing_root = compute_signing_root(
      DepositMessage(
        pubkey: pubkey,
        withdrawal_credentials: builderCredentials,
        amount: depositAmount),
      compute_domain(
        DOMAIN_BUILDER_DEPOSIT, defaultRuntimeConfig.GENESIS_FORK_VERSION))
  BuilderDepositRequest(
    pubkey: pubkey,
    withdrawal_credentials: builderCredentials,
    amount: depositAmount,
    signature: blsSign(MockPrivKeys[index], signing_root.data).toValidatorSig())

proc applyRequests(
    builders: seq[Builder],
    requests: seq[BuilderDepositRequest]): ref gloas.BeaconState =
  let
    state = (ref gloas.BeaconState)(
      slot: currentEpoch.start_slot,
      builders: HashSeq[Builder].init(builders))
    bsb = sortValidatorBuckets(state[].builders.asSeq)
  var next_index: BuilderIndex
  for request in requests:
    process_builder_deposit_request(
      defaultRuntimeConfig, state[], bsb[], request, next_index)
  state

suite "Gloas builder deposit requests within a block":
  test "new builders fill freed slots in order, skip topped-up ones, then append":
    let state = applyRequests(
      @[
        builder(0, FAR_FUTURE_EPOCH, depositAmount),
        builder(1, currentEpoch - 1, 0.Gwei),
        builder(2, currentEpoch + 1, 0.Gwei),
        builder(3, currentEpoch, 0.Gwei),
        builder(4, currentEpoch - 1, depositAmount),
        builder(5, currentEpoch - 1, 0.Gwei)],
      @[
        depositRequest(10),
        depositRequest(3),
        depositRequest(11),
        depositRequest(12),
        depositRequest(13)])
    check:
      state[].builders.len == 8
      state[].builders.item(0).pubkey == mockPubkey(0)
      state[].builders.item(1).pubkey == mockPubkey(10)
      state[].builders.item(2).pubkey == mockPubkey(2)
      state[].builders.item(3).pubkey == mockPubkey(3)
      state[].builders.item(4).pubkey == mockPubkey(4)
      state[].builders.item(5).pubkey == mockPubkey(11)
      state[].builders.item(6).pubkey == mockPubkey(12)
      state[].builders.item(7).pubkey == mockPubkey(13)
      state[].builders.item(1).withdrawable_epoch == FAR_FUTURE_EPOCH
      state[].builders.item(3).withdrawable_epoch ==
        currentEpoch + defaultRuntimeConfig.MIN_BUILDER_WITHDRAWABILITY_DELAY
      state[].builders.item(3).balance == depositAmount
      state[].builders.item(5).balance == depositAmount
