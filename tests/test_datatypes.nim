# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import std/typetraits, unittest2, ../beacon_chain/spec/datatypes/base, ./testutil

suite "Spec datatypes":
  test "Graffiti bytes":
    var
      g1 = GraffitiBytes.init "Hello"
      g2 = default(GraffitiBytes)
      g3 = g2

    distinctBase(g3)[2] = byte(6)

    check:
      $g1 == "Hello"
      $g2 == ""
      $g3 == "0x0000060000000000000000000000000000000000000000000000000000000000"

      g2 == GraffitiBytes.init("")
      g3 == GraffitiBytes.init($g3)
