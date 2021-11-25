# beacon_chain
# Copyright (c) 2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  chronicles,
  ../testutil

# Tests that depend on `mainnet` vs `minimal` compile-time configuration

import
  ./phase0/all_phase0_fixtures,
  ./altair/all_altair_fixtures,
  ./merge/all_merge_fixtures,
  ./test_fixture_fork_choice

summarizeLongTests("ConsensusSpecPreset")
