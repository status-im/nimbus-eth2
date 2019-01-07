# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  unittest, nimcrypto, eth_common, milagro_crypto,
  ../beacon_chain/spec/datatypes, ../beacon_chain/fork_choice

suite "Fork choice rule and attestation pool":
  test "Smoke test":
    var pool = init(AttestationPool, 2)
