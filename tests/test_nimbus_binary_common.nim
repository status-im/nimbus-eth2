# beacon_chain
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import os, unittest2

from ../beacon_chain/nimbus_binary_common import defaultDataDir

## expected values
proc getExpectedPaths(paths: string=""): seq[string] =
  let base = getHomeDir()

  var list = @[
    base / "AppData" / "Roaming" / "Nimbus" / paths,
    base / "Library" / "Application Support" / "Nimbus" / paths,
    base / ".cache" / "nimbus" / paths,
  ]

  list

suite "configuration paths":
  test "Default path":
    check defaultDataDir(()) in getExpectedPaths()

  test "Path with extra path separator":
    check defaultDataDir((), "/extra") in getExpectedPaths("extra")
    check defaultDataDir((), "extra") in getExpectedPaths("extra")

