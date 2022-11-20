# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Stdlib modules
  std/strutils, std/options,
  # Status modules
  stew/results,
  unittest2,
  # Local modules
  ../beacon_chain/validators/validator_pool

proc createValidator*(startEpoch: Epoch,
                      activatedEpoch: Option[Epoch]): AttachedValidator =
  let aepoch =
    if activatedEpoch.isSome():
      Opt.some(activatedEpoch.get())
    else:
      Opt.none(Epoch)
  AttachedValidator(
    startSlot: startEpoch.start_slot(),
    activationEpoch: aepoch
  )

suite "Doppelganger protection test suite":
  test "doppelgangerCheck() test":
    const TestVectors = [
      (0, 9, Epoch(0), some(Epoch(0)), Epoch(0), "TTTTTTTTTT"),
      (0, 9, Epoch(0), some(Epoch(1)), Epoch(0), "1TTTTTTTTT"),
      (0, 9, Epoch(0), some(Epoch(2)), Epoch(0), "11TTTTTTTT"),
      (0, 9, Epoch(0), some(Epoch(3)), Epoch(0), "111TTTTTTT"),
      (0, 9, Epoch(0), some(Epoch(4)), Epoch(0), "1111TTTTTT"),
      (0, 9, Epoch(0), some(Epoch(5)), Epoch(0), "11111TTTTT"),
      (0, 9, Epoch(0), some(Epoch(6)), Epoch(0), "111111TTTT"),
      (0, 9, Epoch(0), some(Epoch(7)), Epoch(0), "1111111TTT"),
      (0, 9, Epoch(0), some(Epoch(8)), Epoch(0), "11111111TT"),
      (0, 9, Epoch(0), some(Epoch(9)), Epoch(0), "111111111T"),

      (0, 9, Epoch(0), some(Epoch(5)), Epoch(0), "11111TTTTT"),
      (0, 9, Epoch(0), some(Epoch(5)), Epoch(1), "11111TTTTT"),
      (0, 9, Epoch(0), some(Epoch(5)), Epoch(2), "11111TTTTT"),
      (0, 9, Epoch(0), some(Epoch(5)), Epoch(3), "11111TTTTT"),
      (0, 9, Epoch(0), some(Epoch(5)), Epoch(4), "11111TTTTT"),
      (0, 9, Epoch(0), some(Epoch(5)), Epoch(5), "11111TTTTT"),
      (0, 9, Epoch(0), some(Epoch(5)), Epoch(6), "111112FFTT"),
      (0, 9, Epoch(0), some(Epoch(5)), Epoch(7), "1111122FFT"),
      (0, 9, Epoch(0), some(Epoch(5)), Epoch(8), "11111222FF"),
      (0, 9, Epoch(0), some(Epoch(5)), Epoch(9), "111112222F"),

      (0, 9, Epoch(1), some(Epoch(0)), Epoch(0), "2FFTTTTTTT"),
      (0, 9, Epoch(2), some(Epoch(0)), Epoch(0), "22FFTTTTTT"),
      (0, 9, Epoch(3), some(Epoch(0)), Epoch(0), "222FFTTTTT"),
      (0, 9, Epoch(4), some(Epoch(0)), Epoch(0), "2222FFTTTT"),
      (0, 9, Epoch(5), some(Epoch(0)), Epoch(0), "22222FFTTT"),
      (0, 9, Epoch(6), some(Epoch(0)), Epoch(0), "222222FFTT"),
      (0, 9, Epoch(7), some(Epoch(0)), Epoch(0), "2222222FFT"),
      (0, 9, Epoch(8), some(Epoch(0)), Epoch(0), "22222222FF"),
      (0, 9, Epoch(9), some(Epoch(0)), Epoch(0), "222222222F"),

      (0, 9, Epoch(0), none(Epoch), Epoch(0),    "1111111111"),
      (0, 9, Epoch(1), none(Epoch), Epoch(0),    "1111111111"),
      (0, 9, Epoch(2), none(Epoch), Epoch(0),    "1111111111"),
      (0, 9, Epoch(3), none(Epoch), Epoch(0),    "1111111111"),
      (0, 9, Epoch(4), none(Epoch), Epoch(0),    "1111111111"),
      (0, 9, Epoch(5), none(Epoch), Epoch(0),    "1111111111"),
      (0, 9, Epoch(6), none(Epoch), Epoch(0),    "1111111111"),
      (0, 9, Epoch(7), none(Epoch), Epoch(0),    "1111111111"),
      (0, 9, Epoch(8), none(Epoch), Epoch(0),    "1111111111"),
      (0, 9, Epoch(9), none(Epoch), Epoch(0),    "1111111111"),

      (0, 9, Epoch(0), none(Epoch), Epoch(0),    "1111111111"),
      (0, 9, Epoch(0), none(Epoch), Epoch(1),    "1111111111"),
      (0, 9, Epoch(0), none(Epoch), Epoch(2),    "1111111111"),
      (0, 9, Epoch(0), none(Epoch), Epoch(3),    "1111111111"),
      (0, 9, Epoch(0), none(Epoch), Epoch(4),    "1111111111"),
      (0, 9, Epoch(0), none(Epoch), Epoch(5),    "1111111111"),
      (0, 9, Epoch(0), none(Epoch), Epoch(6),    "1111111111"),
      (0, 9, Epoch(0), none(Epoch), Epoch(7),    "1111111111"),
      (0, 9, Epoch(0), none(Epoch), Epoch(8),    "1111111111"),
      (0, 9, Epoch(0), none(Epoch), Epoch(9),    "1111111111")
    ]

    for test in TestVectors:
      let validator = createValidator(test[2], test[3])
      let value =
        block:
          var res = ""
          for index in test[0] .. test[1]:
            let epoch = Epoch(uint64(index))
            let dres = validator.doppelgangerCheck(epoch, test[4])
            if dres.isErr():
              let errorMsg = $dres.error()
              if errorMsg.startsWith("Validator is not activated"):
                res.add("1")
              elif errorMsg.startsWith("Validator is not started"):
                res.add("2")
              else:
                res.add("E")
            else:
              if dres.get():
                res.add("T")
              else:
                res.add("F")
          res
      check value == test[5]
