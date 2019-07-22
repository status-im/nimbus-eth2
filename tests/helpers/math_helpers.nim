# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

func round_multiple_down*(x: uint64, n: uint64): uint64 {.inline.} =
  ## Round the input to the previous multiple of "n"
  result = x - x mod n

func round_multiple_up*(x: uint64, n: uint64): uint64 {.inline.} =
  ## Round the input to the next multiple of "n"
  result = ((x + n - 1) div n) * n
