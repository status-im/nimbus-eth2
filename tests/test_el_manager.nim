# beacon_chain
# Copyright (c) 2021-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  unittest2,
  ../beacon_chain/el/el_conf,
  ./testutil

suite "Eth1 monitor":
  test "Rewrite URLs":
    var
      gethHttpUrl = "http://localhost:8545"
      gethHttpsUrl = "https://localhost:8545"
      gethWsUrl = "ws://localhost:8545"
      unspecifiedProtocolUrl = "localhost:8545"

    fixupWeb3Urls gethHttpUrl
    fixupWeb3Urls gethHttpsUrl
    fixupWeb3Urls gethWsUrl
    fixupWeb3Urls unspecifiedProtocolUrl

    check:
      gethHttpUrl == "http://localhost:8545"
      gethHttpsUrl == "https://localhost:8545"
      unspecifiedProtocolUrl == "ws://localhost:8545"

      gethWsUrl == "ws://localhost:8545"
