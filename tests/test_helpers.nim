# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  sequtils, unittest,
  ../beacon_chain/spec/[helpers]

suite "Spec helpers":
  test "is_power_of_2 should do its job":
    check:
      is_power_of_2(1) == true
      is_power_of_2(2) == true
      is_power_of_2(3) == false
      is_power_of_2(4) == true
      is_power_of_2(not 0'u64) == false
