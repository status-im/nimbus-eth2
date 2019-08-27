# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  ../../beacon_chain/spec/digest

proc `*`*(a: static array[1, byte], n: static int): Eth2Digest {.compileTime.} =
  assert n == 32
  for mbyte in result.data.mitems:
    mbyte = a[0]
