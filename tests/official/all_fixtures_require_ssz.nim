# beacon_chain
# Copyright (c) 2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# All non-pure SSZ tests that require the -d:ssz_testing
# to ignore invalid BLS signature in EF test vectors
# https://github.com/status-im/nimbus-eth2/issues/374

import ../testutil

import
  ./phase0/all_phase0_fixtures_require_ssz,
  ./altair/all_altair_fixtures_require_ssz

summarizeLongTests("FixtureAll")
