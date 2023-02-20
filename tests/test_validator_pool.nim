# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  unittest2,
  ../beacon_chain/validators/validator_pool

func makeValidatorAndIndex(
    index: ValidatorIndex, activation_epoch: Epoch): Opt[ValidatorAndIndex] =
  Opt.some ValidatorAndIndex(
    index: index,
    validator: Validator(activation_epoch: activation_epoch)
  )

suite "Validator pool":
  test "Doppelganger for genesis validator":
    let
      v = AttachedValidator(activationEpoch: FAR_FUTURE_EPOCH)

    check:
      not v.triggersDoppelganger(GENESIS_EPOCH) # no check
      not v.doppelgangerReady(GENESIS_EPOCH.start_slot) # no activation

    v.updateValidator(makeValidatorAndIndex(ValidatorIndex(1), GENESIS_EPOCH))

    check:
      not v.triggersDoppelganger(GENESIS_EPOCH) # no check
      v.doppelgangerReady(GENESIS_EPOCH.start_slot) # ready in activation epoch
      not v.doppelgangerReady((GENESIS_EPOCH + 1).start_slot) # old check

    v.doppelgangerChecked(GENESIS_EPOCH)

    check:
      v.triggersDoppelganger(GENESIS_EPOCH) # checked, triggered
      v.doppelgangerReady((GENESIS_EPOCH + 1).start_slot) # checked
      v.doppelgangerReady((GENESIS_EPOCH + 2).start_slot) # 1 slot lag allowance
      not v.doppelgangerReady((GENESIS_EPOCH + 2).start_slot + 1) # old check

  test "Doppelganger for validator that activates in same epoch as check":
    let
      v = AttachedValidator(activationEpoch: FAR_FUTURE_EPOCH)
      now = Epoch(10).start_slot()

    check: # We don't know when validator activates so we wouldn't trigger
      not v.triggersDoppelganger(GENESIS_EPOCH)
      not v.triggersDoppelganger(now.epoch())

      not v.doppelgangerReady(GENESIS_EPOCH.start_slot)
      not v.doppelgangerReady(now)

    v.updateValidator(makeValidatorAndIndex(ValidatorIndex(5), FAR_FUTURE_EPOCH))

    check: # We still don't know when validator activates so we wouldn't trigger
      not v.triggersDoppelganger(GENESIS_EPOCH)
      not v.triggersDoppelganger(now.epoch())

      not v.doppelgangerReady(GENESIS_EPOCH.start_slot)
      not v.doppelgangerReady(now)

    v.updateValidator(makeValidatorAndIndex(ValidatorIndex(5), now.epoch()))

    check: # No check done yet
      not v.triggersDoppelganger(GENESIS_EPOCH)
      not v.triggersDoppelganger(now.epoch())

      not v.doppelgangerReady(GENESIS_EPOCH.start_slot)
      v.doppelgangerReady(now)

    v.doppelgangerChecked(GENESIS_EPOCH)

    check:
      v.triggersDoppelganger(GENESIS_EPOCH)
      not v.triggersDoppelganger(now.epoch())

      not v.doppelgangerReady(GENESIS_EPOCH.start_slot)
      v.doppelgangerReady(now)
