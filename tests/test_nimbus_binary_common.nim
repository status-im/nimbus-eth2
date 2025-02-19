# beacon_chain
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  os,
  unittest2,
  stew/byteutils

from  ../beacon_chain/nimbus_binary_common import defaultDataDir

## expected values for dafault dir tests
when defined(windows):
  const expectedBase = getHomeDir() / "AppData" / "Roaming" / "Nimbus"
elif defined(macosx):
  const expectedBase = getHomeDir() / "Library" / "Application Support" / "Nimbus"
else:
  const expectedBase = getHomeDir() / ".cache" / "nimbus"

suite "Nimbus clients binary common":
  test "Default path without extra paths":
    check defaultDataDir(()) == expectedBase

  test "Relative extra path is appended":
    check defaultDataDir((), "extra") == expectedBase / "extra"

  test "Absolute extra path is used as is":
    let absPath = "/my/absolute/path"
    check defaultDataDir((), absPath) == expectedBase / "my" / "absolute" / "path"

  test "Handles empty extra path correctly":
    check defaultDataDir((), "") == expectedBase
