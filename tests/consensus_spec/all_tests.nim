# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

# BLS test vectors are covered by nim-blscurve:
# https://github.com/status-im/nim-blscurve/blob/master/tests/eth2_vectors.nim

# Tests that do not depend on `mainnet` vs `minimal` compile-time configuration

import
  ./test_fixture_fork_digest,
  ./test_fixture_gloas_builder_onboarding,
  ./test_fixture_networking
