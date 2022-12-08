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

suite "Validator pool":
  test "Doppelganger for genesis validator":
    let
      v = AttachedValidator(activationEpoch: FAR_FUTURE_EPOCH)

    check:
      not v.triggersDoppelganger(GENESIS_EPOCH)

    v.updateValidator(ValidatorIndex(1), GENESIS_EPOCH)

    check:
      not v.triggersDoppelganger(GENESIS_EPOCH)

  test "Doppelganger for validator that activates in same epoch as check":
    let
      v = AttachedValidator(activationEpoch: FAR_FUTURE_EPOCH)
      now = Epoch(10).start_slot()

    check: # We don't know when validator activates so we wouldn't trigger
      not v.triggersDoppelganger(GENESIS_EPOCH)
      not v.triggersDoppelganger(now.epoch())

    v.updateValidator(ValidatorIndex(5), FAR_FUTURE_EPOCH)

    check: # We still don't know when validator activates so we wouldn't trigger
      not v.triggersDoppelganger(GENESIS_EPOCH)
      not v.triggersDoppelganger(now.epoch())

    v.updateValidator(ValidatorIndex(5), now.epoch())

    check:
      # Activates in current epoch, shouldn't trigger
      not v.triggersDoppelganger(now.epoch())

  test "Doppelganger for validator that activates in previous epoch":
    let
      v = AttachedValidator(activationEpoch: FAR_FUTURE_EPOCH)
      now = Epoch(10).start_slot()

    v.updateValidator(ValidatorIndex(5), now.epoch() - 1)

    check:
      # Already activated, should trigger
      v.triggersDoppelganger(now.epoch())

  test "Doppelganger for validator that activates in future epoch":
    let
      v = AttachedValidator(activationEpoch: FAR_FUTURE_EPOCH)
      now = Epoch(10).start_slot()

    v.updateValidator(ValidatorIndex(5), now.epoch() + 1)

    check:
      # Activates in the future, should not be checked
      not v.triggersDoppelganger(now.epoch())

  test "Doppelganger for already active validator":
    let
      v = AttachedValidator(activationEpoch: FAR_FUTURE_EPOCH)
      now = Epoch(10).start_slot()

    v.updateValidator(ValidatorIndex(5), now.epoch() - 4)

    check:
      v.triggersDoppelganger(now.epoch)

    v.updateDoppelganger(now.epoch())

    check:
      not v.triggersDoppelganger(now.epoch + 1)

  test "Activation after check":
    let
      v = AttachedValidator(activationEpoch: FAR_FUTURE_EPOCH)
      now = Epoch(10).start_slot()

    v.updateDoppelganger(now.epoch())

    check:
      not v.triggersDoppelganger(now.epoch)

    v.updateValidator(ValidatorIndex(5), now.epoch())

    check: # already proven not to validate
      not v.triggersDoppelganger(now.epoch)

  test "Future activation after check":
    let
      v = AttachedValidator(activationEpoch: FAR_FUTURE_EPOCH)
      now = Epoch(10).start_slot()

    v.updateDoppelganger(now.epoch())
    v.updateValidator(ValidatorIndex(5), now.epoch() + 1)

    check: # doesn't trigger check just after activation
      not v.triggersDoppelganger(now.epoch() + 1)
