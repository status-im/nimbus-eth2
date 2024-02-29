# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  ../../beacon_chain/spec/digest

func `*`*(a: static array[1, byte], n: static int): static Eth2Digest =
  doAssert n == 32
  for mbyte in result.data.mitems:
    mbyte = a[0]
