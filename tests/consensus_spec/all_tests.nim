# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

# BLS test vectors are covered by nim-blscurve:
# https://github.com/status-im/nim-blscurve/blob/master/tests/eth2_vectors.nim

# Tests that do not depend on `mainnet` vs `minimal` compile-time configuration

import
  ./test_fixture_kzg,
  ./test_fixture_ssz_generic_types
