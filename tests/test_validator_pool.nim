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

    v.updateValidator(ValidatorIndex(1), GENESIS_EPOCH)

    check:
      v.checkingDoppelganger()

      v.updateDoppelganger(GENESIS_EPOCH, false).isOk()
      v.updateDoppelganger(GENESIS_EPOCH, true).isOk()

      not v.checkingDoppelganger()

  test "Doppelganger for validator that activates while running":
    let
      v = AttachedValidator(activationEpoch: FAR_FUTURE_EPOCH)
      now = Epoch(10).start_slot()

    check:
      v.checkingDoppelganger()

    v.updateValidator(ValidatorIndex(5), FAR_FUTURE_EPOCH)

    check:
      v.updateDoppelganger(now.epoch(), false).isOk()
      v.updateDoppelganger(now.epoch(), true).isOk()

      v.checkingDoppelganger()

    v.updateValidator(ValidatorIndex(5), now.epoch() + 1)

    check:
      # Activates in the future, should not be checked
      not v.checkingDoppelganger()

  test "Doppelganger for already active validator":
    let
      v = AttachedValidator(activationEpoch: FAR_FUTURE_EPOCH)
      now = Epoch(10).start_slot()

    v.updateValidator(ValidatorIndex(5), now.epoch() - 4)

    check:
      v.checkingDoppelganger()
      v.updateDoppelganger(now.epoch(), false).isOk()

    check:
      v.checkingDoppelganger()

    check:
      v.updateDoppelganger(now.epoch() + 1, false).isOk()

    check:
      not v.checkingDoppelganger()

  test "Trigger doppelganger check":
    let
      v = AttachedValidator(activationEpoch: FAR_FUTURE_EPOCH)
      now = Epoch(10).start_slot()

    v.updateValidator(ValidatorIndex(5), now.epoch() - 4)

    check:
      v.checkingDoppelganger()
      v.updateDoppelganger(now.epoch(), true).isErr()
